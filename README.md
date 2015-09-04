# Munin Panic Status Board Integration

This repository contains a simple Python script which can be used to export
data from [Munin's][munin] raw RRD files to a JSON format suitable for use
with the line and bar graphs of Panic Inc's iPad
[Status Board 2][status-board] app. If you already have a server on which
you use Munin to monitor its status, therefore, you can trivially get that
data live updating on your iPad along with all the other views that
Status Board 2 supports.

## Setup

The code is all contained in a single script, `munin-to-status-board.py`,
which you can install anywhere you fancy. This script expects one or
more configuration files as its parameters which specify the source RRD
files to use and also the graphs to generate. Typically you'll execute this
via a crontab entry like this:

    */5 * * * *     /path/to/munin-to-status-board.py /path/to/config.cfg

## Configuration

The configuration can be split across as many files as you like -- the
contents of all those specified on the command-line will be merged. The
basic syntax is that expected by Python's `ConfigParser` module, which is
similar to the Windows `.ini` file format.

The file is split into sections specified by a heading in square brackets.
Each section specifies either a data source or a graph, and there is a special
`settings` section which currently just contains logging configuration.

An annotated sample configuration is shown below to demonstrate the available
settings:

    [DEFAULT]
    # As per Python's ConfigParser module, the DEFAULT section can be used
    # to provide default values for other sections and also names to be
    # substituted in as part of other settings with syntax %(value)s.
    srcprefix: /var/lib/munin/com/example.com
    webroot: /var/lib/www/dashboard
    logroot: /var/log

    [settings]
    # If specified, logging will be performed to the named file. If not,
    # logging will be done to stderr. If --debug is specified, stderr logging
    # will be done separately and in addition to logging to this file.
    logfile: %(logroot)s/munintostatus.log

    # Should be one of CRITICAL, ERROR, WARNING, INFO and DEBUG - this affects
    # the level of logging into the log file.
    loglevel: INFO

    # A section starting with the word "source" defines a source - the rest
    # of the name is arbitrary but is used in later "graph" sections to
    # tie sources into graphs.
    [source net-traffic-up]

    # The title of the data set in the graph legend.
    title: TX

    # The path of the RRD file to populate this data source.
    source-file: %(srcprefix)s-if_venet0-up-d.rrd

    # Optional: the colour of the line on the graph.
    color: green
    
    [source net-traffic-down]
    title: RX
    source-file: %(srcprefix)s-if_venet0-down-d.rrd
    color: red

    # A section starting with the word "graph" defines a graph - the rest
    # of the name is arbitrary and is currently not used anywhere.
    [graph net-traffic]

    # The title of the whole graph.
    title: Net Traffic (bit/s)

    # Optionally set scale to K or M, which will cause the graph to scale
    # values to thousands or millions respectively, and also cause the K
    # or M suffix to be added to values on the y-axis.
    scale: K

    # The type of the graph can be line or bar.
    type: line

    # The full path of the generated JSON text file.
    output-file: %(webroot)s/network.json

    # The interval at which the status board should re-fetch the JSON file.
    refresh-every: 5m

    # The interval between data points in the generated set.
    resolution: 5m

    # The period of time over which to return data - the combination of
    # this and 'resolution' determines the number of data points.
    period: 6h

    # A comma-separated list of the names of sources defined by earlier
    # "source" sections. Each of these sources will become one data set
    # shown on the graph.
    sources: net-traffic-up, net-traffic-down


## Support

If you have any questions then feel free to get in touch, I'll help however
I can. The whole thing is quite simple, however, so you might find you get
a faster response just reading the code yourself.

[munin]: http://munin-monitoring.org

[status-board]: https://panic.com/statusboard/