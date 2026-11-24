""" Optional YAML overrides for config.py.

config.py holds phxd's defaults. Any of its settings can be overridden by
a YAML file, read at startup, so a deployment (e.g. a Docker container
with the file mounted in) can be reconfigured with a restart instead of
editing config.py and rebuilding the image.

The file is looked up at ``$PHXD_CONFIG`` if set, otherwise ``phxd.yaml``
next to config.py. Keys are config.py setting names (case-insensitive)::

    server_name: "My Hotline server"
    server_description: "Since 1998"
    tracker_list:
      - tracker.preterhuman.net:5499
      - hotline.ubersoft.org        # port defaults to 5499
    log_level: INFO

Unknown settings and values of the wrong type stop the server with an
error instead of being silently ignored.
"""
from __future__ import absolute_import

import os

DEFAULT_TRACKER_PORT = 5499

# Settings computed from another one in config.py, as
# derived name -> ( base name , how to compute it ). When the YAML file
# overrides the base setting but not the derived one, the derived value
# is recomputed so e.g. moving db_file_basepath also moves the log file.
DERIVED_SETTINGS = {
    "DB_FILE_NEWSDIR": ( "DB_FILE_BASEPATH" , lambda c: os.path.join( c["DB_FILE_BASEPATH"] , "db_news" ) ),
    "DB_FILE_ACCOUNTS": ( "DB_FILE_BASEPATH" , lambda c: os.path.join( c["DB_FILE_BASEPATH"] , "db_accounts.txt" ) ),
    "DB_FILE_LOG": ( "DB_FILE_BASEPATH" , lambda c: os.path.join( c["DB_FILE_BASEPATH"] , "db_log.txt" ) ),
    "DB_FILE_BANLIST": ( "DB_FILE_BASEPATH" , lambda c: os.path.join( c["DB_FILE_BASEPATH"] , "db_banlist.txt" ) ),
    "LOG_FILE": ( "DB_FILE_BASEPATH" , lambda c: os.path.join( c["DB_FILE_BASEPATH"] , "phxd.log" ) ),
    "LINK_PORT": ( "SERVER_PORT" , lambda c: c["SERVER_PORT"] + 3 ),
}

LOG_LEVELS = ( "DEBUG" , "INFO" , "WARNING" , "ERROR" , "CRITICAL" )


class ConfigError( Exception ):
    pass


def defaultConfigPath( configDir ):
    return os.environ.get( "PHXD_CONFIG" ) or os.path.join( configDir , "phxd.yaml" )


def _trackerList( value ):
    """ Accepts "host:port" / "host" strings, [host, port] pairs or
    {host: ..., port: ...} mappings, and returns (host, port) tuples. """
    if not isinstance( value , list ):
        raise ConfigError( "tracker_list must be a list" )
    trackers = []
    for entry in value:
        if isinstance( entry , str ):
            host , _ , port = entry.partition( ":" )
            port = port or DEFAULT_TRACKER_PORT
        elif isinstance( entry , (list , tuple) ) and len( entry ) == 2:
            host , port = entry
        elif isinstance( entry , dict ) and "host" in entry:
            host , port = entry["host"] , entry.get( "port" , DEFAULT_TRACKER_PORT )
        else:
            raise ConfigError( "invalid tracker_list entry: %r" % ( entry , ) )
        try:
            port = int( port )
        except ( TypeError , ValueError ):
            raise ConfigError( "invalid tracker port in %r" % ( entry , ) )
        if not host:
            raise ConfigError( "invalid tracker_list entry: %r" % ( entry , ) )
        trackers.append( ( str( host ) , port ) )
    return trackers


def _checkType( key , value , default ):
    """ Values must match the type of the config.py default. """
    if default is None:
        return value
    if isinstance( default , bool ):
        if not isinstance( value , bool ):
            raise ConfigError( "%s must be true or false, not %r" % ( key.lower() , value ) )
        return value
    if isinstance( default , int ):
        if isinstance( value , bool ) or not isinstance( value , int ):
            raise ConfigError( "%s must be a whole number, not %r" % ( key.lower() , value ) )
        return value
    if isinstance( default , float ):
        if isinstance( value , bool ) or not isinstance( value , (int , float) ):
            raise ConfigError( "%s must be a number, not %r" % ( key.lower() , value ) )
        return float( value )
    if isinstance( default , str ):
        if not isinstance( value , str ):
            raise ConfigError( "%s must be a string, not %r" % ( key.lower() , value ) )
        return value
    if isinstance( default , list ):
        if not isinstance( value , list ):
            raise ConfigError( "%s must be a list, not %r" % ( key.lower() , value ) )
        return value
    return value


def applyOverrides( config , path ):
    """ Applies the overrides from the YAML file at ``path`` to the
    ``config`` dict (config.py's globals). Returns the names of the
    settings that were overridden; a missing file overrides nothing. """
    if not os.path.exists( path ):
        return []
    try:
        import yaml
    except ImportError:
        raise ConfigError( "%s exists but PyYAML is not installed (pip install PyYAML)" % path )
    with open( path , "r" , encoding = "utf-8" ) as fp:
        try:
            data = yaml.safe_load( fp )
        except yaml.YAMLError as e:
            raise ConfigError( "invalid YAML in %s: %s" % ( path , e ) )
    if data is None:
        return []
    if not isinstance( data , dict ):
        raise ConfigError( "%s must contain a mapping of setting: value" % path )

    overridden = []
    for key , value in data.items():
        name = str( key ).upper()
        if name == "LOG_LEVEL":
            if not isinstance( value , str ) or value.upper() not in LOG_LEVELS:
                raise ConfigError( "log_level must be one of %s" % ", ".join( LOG_LEVELS ) )
            value = value.upper()
        elif name.startswith( "_" ) or name not in config or callable( config[name] ) \
                or type( config[name] ).__name__ == "module":
            raise ConfigError( "unknown setting %r in %s" % ( key , path ) )
        elif name == "TRACKER_LIST":
            value = _trackerList( value )
        else:
            value = _checkType( name , value , config[name] )
        config[name] = value
        overridden.append( name )

    for name , ( base , compute ) in DERIVED_SETTINGS.items():
        if base in overridden and name not in overridden and name in config:
            config[name] = compute( config )
    return overridden


def loadOverrides( config , configDir ):
    """ Entry point used by config.py: applies overrides, or exits with a
    readable message if the YAML file is invalid. """
    path = defaultConfigPath( configDir )
    try:
        return applyOverrides( config , path )
    except ConfigError as e:
        raise SystemExit( "phxd: configuration error: %s" % e )
