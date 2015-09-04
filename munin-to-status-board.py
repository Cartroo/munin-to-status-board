#!/usr/bin/python

"""Translate Munin RRD files into JSON suitable for Status Board on iPad."""

import argparse
import ConfigParser
import json
import logging
import logging.handlers
import math
import os
import subprocess
import sys
import time


class MuninToStatusboardError(Exception):
    """Base class for all errors."""
    pass

class UsageError(MuninToStatusboardError):
    """User error on the command-line."""
    pass

class ConfigError(MuninToStatusboardError):
    """User error in the config file."""
    pass


def get_arg_parser():
    """Build the argparser parser."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("config_files", metavar="FILE", nargs="+",
            help="configuration file(s)")
    parser.add_argument("--debug", "-d", action="store_true", default=False,
            help="enable debug output to stderr")
    return parser


def config_get(config, section, option, default=None):
    """Add a default to ConfigParser.get(), similar to dict.get()."""

    if config.has_option(section, option):
        return config.get(section, option)
    else:
        return default


PERIOD_SUFFIXES = {
    "m": 60,
    "h": 3600,
    "d": 86400
}

def config_get_period(config, section, option, default):
    """Parse a period sepcification."""

    spec = config_get(config, section, option)
    if not spec:
        return default
    spec = spec.strip().lower()
    suffix = spec[-1]
    try:
        if suffix in PERIOD_SUFFIXES:
            return int(spec[:-1]) * PERIOD_SUFFIXES[spec[-1]]
        return int(spec)
    except ValueError:
        raise ConfigError("invalid period specified")


class Source(object):
    """Represents an RRD file data source."""

    TIME_FMT = "%a %d %H:%M"
    SUBDAY_TIME_FMT = "%H:%M"

    def __init__(self, logger, config, section):
        self.logger = logger
        self.title = config_get(config, section, "title")
        self.source_file = config_get(config, section, "source-file")
        if self.title is None or self.source_file is None:
            raise ConfigError("'title' and/or 'source-file' missing")
        self.colour = config_get(config, section, "color")
        logger.debug("new source: title=%r, source_file=%r, colour=%r",
                     self.title, self.source_file, self.colour)


    def __repr__(self):
        return ("Source(title=%r, source_file=%r, colour=%r)" %
                (self.title, self.source_file, self.colour))


    def get_data(self, resolution, period):
        """Return the full data specification for this source."""

        ret = {
            "title": self.title,
            "datapoints": self.get_rrd_contents(resolution, period)
        }
        if self.colour is not None:
            ret["color"] = self.colour

        self.logger.debug("data spec: %r", ret)
        return ret


    def get_rrd_contents(self, resolution, period):
        """Return parsed output from specified RRD."""

        time_fmt = self.SUBDAY_TIME_FMT if period <= 86400 else self.TIME_FMT
        data_points = []
        cmdline = ["rrdtool", "fetch", self.source_file, "AVERAGE", "-r",
                   str(resolution), "-s", "-%s" % (period,)]
        self.logger.debug("exec: %r", cmdline)
        output = subprocess.check_output(cmdline)
        for line in (i for i in output.splitlines() if ":" in i):
            try:
                ts_str, value_str = line.split(":", 1)
                time_str = time.strftime(time_fmt, time.localtime(int(ts_str)))
                value = float(value_str)
                value = 0 if math.isnan(value) else value
                data_points.append({"title": time_str, "value": value})
            except ValueError:
                pass

        return data_points


class Graph(object):
    """Represents a graph definition plotted from sources."""

    SCALES = {
        "K": 1000,
        "M": 1000000
    }


    def __init__(self, logger, config, section, all_sources):
        self.logger = logger
        self.title = config_get(config, section, "title")
        self.output_file = config_get(config, section, "output-file")
        sources = config_get(config, section, "sources")
        if self.title is None or self.output_file is None or sources is None:
            raise ConfigError("'title', 'output-file', or 'sources' missing")

        try:
            self.sources = set(all_sources[i.strip().lower()]
                               for i in sources.split(","))
        except KeyError, e:
            raise ConfigError("undefined source %r" % (e.args[0],))

        self.scale = config_get(config, section, "scale")
        if self.scale is not None:
            self.scale = self.scale.upper().strip()
            if self.scale not in self.SCALES:
                raise ConfigError("unknown scale %r" % (self.scale,))

        self.graph_type = config_get(config, section, "type", "line").lower()
        if self.graph_type not in ("line", "bar"):
            raise ConfigError("unknown graph type %r" % (self.graph_type,))

        self.period = config_get_period(config, section, 'period', 3600 * 24)
        self.resolution = config_get_period(config, section, 'resolution', 300)
        self.refresh = config_get_period(
                config, section, 'refresh-every', self.resolution)

        logger.debug("new graph: " + ", ".join('%s=%r' % (i, getattr(self, i))
                for i in ("title", "output_file", "sources", "scale",
                          "graph_type", "period", "resolution", "refresh")))


    def write(self):
        """Outputs the graph specification JSON file."""

        source_args = [self.resolution, self.period]
        with open(self.output_file, "w") as fd:
            graph_def = {
                "graph": {
                    "title": self.title,
                    "refreshEveryNSeconds": str(self.refresh),
                    "type": self.graph_type,
                    "datasequences":
                        [i.get_data(*source_args) for i in self.sources]
                }
            }
            if self.scale is not None:
                graph_def["graph"]["yAxis"] = {
                    "units": {
                        "suffix": self.scale
                    },
                    "scaleTo": self.SCALES[self.scale]
                }
            self.logger.info("writing %r", self.output_file)
            json.dump(graph_def, fd, indent=4, separators=(',', ': '))


def write_graphs(logger, config):
    """Processes each graph definition in turn."""

    # Pull graph and source definitions out of config.
    graphs = set()
    sources = {}
    for section in config.sections():
        if section == "settings":
            continue
        items = section.split(None, 1)
        if len(items) < 2:
            logger.warning("invalid section name %r" % (section,))
        elif items[0].lower() == "graph":
            logger.debug("graph section: %r", section)
            graphs.add(section)
        elif items[0].lower() == "source":
            logger.debug("source section: %r", section)
            try:
                sources[items[1].lower()] = Source(logger, config, section)
            except ConfigError, e:
                raise ConfigError("%s: %s" % (section, e))
        else:
            logger.warning("invalid section name %r" % (section,))

    # Process each graph definition in turn
    logger.info("writing %d graph files", len(graphs))
    for section in graphs:
        try:
            Graph(logger, config, section, sources).write()
        except ConfigError, e:
            raise ConfigError("%s: %s" % (section, e))


def setup_default_logging(name):
    """Sets up an initial logger for stderr."""

    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # Create console handler and set level to warnings only.
    stderr_handler = logging.StreamHandler()
    stderr_handler.setLevel(logging.WARNING)

    # Create formatter and add to handler.
    formatter = logging.Formatter(
        "%(asctime)s %(name)s %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")
    stderr_handler.setFormatter(formatter)

    # Add handler to logger and also set it as an attribute to
    # aid later removal (I don't like using logger.handlers as
    # it's undocumented).
    logger.addHandler(stderr_handler)
    logger.__stderr_handler = stderr_handler

    return logger


def setup_logging(logger, config, args):
    """Setup logging to a file, if configured."""

    if config.has_option("settings", "logfile"):
        logfile = config.get("settings", "logfile")
        logfile_handler = logging.handlers.WatchedFileHandler(logfile)
        if config.has_option("settings", "loglevel"):
            level_name = config.get("settings", "loglevel").strip().upper()
            level = logging.getLevelName(level_name)
            if not isinstance(level, int):
                raise ConfigError("invalid log level %r" % (level_name,))
        else:
            level = logging.INFO
        logfile_handler.setLevel(level)
        logger.__log_file_handler = logfile_handler

        formatter = logging.Formatter(
            "%(asctime)s %(name)s %(levelname)s: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S")
        logfile_handler.setFormatter(formatter)
        logger.addHandler(logfile_handler)

        if not args.debug:
            logger.removeHandler(logger.__stderr_handler)
            del logger.__stderr_handler

    if args.debug:
        logger.__stderr_handler.setLevel(logging.DEBUG)


def main(args):
    """Main entry point."""

    script_name = os.path.basename(args[0])
    logger = setup_default_logging(script_name)
    try:
        parser = get_arg_parser()
        args = parser.parse_args()

        # Validate config files (ConfigParser ignores non-existent files)
        config_files = set(args.config_files)
        valid_configs = set(i for i in config_files if os.access(i, os.R_OK))
        for filename in config_files - valid_configs:
            logger.warning("ignoring missing/unreadable config %r", filename)
        if not valid_configs:
            raise UsageError("must specify at least one valid config file")

        # Load configuration
        config_parser = ConfigParser.SafeConfigParser()
        config_parser.read(valid_configs)
        setup_logging(logger, config_parser, args)

        write_graphs(logger, config_parser)

    except UsageError, e:
        logger.error("usage error: %s", e)
        return 1

    except ConfigError, e:
        logger.error("config error: %s", e)
        return 1

    except Exception, e:
        logger.critical("unhandled exception: %s", e, exc_info=True)
        return 2

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
