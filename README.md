# phxd
**phxd (Python hxd)** is a fully functional [**Hotline**](https://en.wikipedia.org/wiki/Hotline_Communications) pure **Python** server written with **Twisted**, originally written by **Vertigo** (avaraline.net) and later extended with hybrid **IRC support** by [**kang**](https://github.com/kangsterizer). The **IRC support** allows connecting to phxd using an **IRC client** and maps several **HLX** (Hotline) functions, like **public chat**, **private messages** and more. A **tracker client** functionality to register a **phxd** server instance with a (**passwordless**, public) **Hotline tracker** server was then later added.

# Dependencies
* **phxd** is only compatible with **Python 2**, and there is no support for Python 3 or any plans to implement it.
* **phxd** is **Twisted** based, and as such requires **Twisted** to run. This should be the only dependency required to run it on any standard **Python 2** version. **Twisted** can be installed via pip:
```
pip install twisted
```

# Configuration

## Configuration attributes
**phxd**'s configuration is stored in the config.py Python file. The configuration can be altered directly inside the file (advanced users) or via a supplied interactive tool.

The program offers two methods of storing server related data (accounts, news, etc.): **"MySQL"** and **"Text"**.
* **"MySQL"** allows connecting to a mysql database instance with user/pass specified in the config.py file, and will use or create a new config.py "DB\_NAME" database to store **phxd** data. Note that storing **phxd** data using **"MySQL"** has not been tested recently.
* **"Text"** database will create a few `db_*.tx` files and directories containing the data generated by running **phxd** such as accounts data, banlist, news etc.

If the config.py **"ENABLE\_FILE\_LOG"** is set to **True**, **phxd** will logs its internal events to the **"LOG\_FILE"** path, rotating logfiles every **"LOG\_MAX\_SIZE\_MBYTES"**, keeping a maximum of **"MAX\_LOG\_FILES"**.

The **"SERVER\_NAME"** and **"SERVER\_DESCRIPTION"** attributes will be used to advertise the server to Hotline tracker servers.
By default, the **phxd** instance will not be listed on any trackers. This can be changed by editing the **"TRACKER\_LIST"** config attribute. Note that this attribute is not configurable via the interactive configurator tool and must be modified directly inside the config.py file. To enable trackers, edit the property so as to create a list of tuples, each composed with a hostname string (it can also be an IP address) and a port integer. The Hotline server default port for advertising servers is **5499**, this differs to the port used by clients to list servers. The following configuration will get your server listed on the (currently) most active Hotline trackers running:

```
TRACKER_LIST=[("tracker.preterhuman.net", 5499),
              ("tracked.agent79.org", 5499),
              ("hotline.duckdns.org", 5499),
              ("tracked.stickytack.com", 5499),
              ("tracked.nailbat.com", 5499),
              ("hotline.ubersoft.org", 5499)]
```

## First time configuration
Before running **phxd**, you should either edit the config.py file directly with the proper configuration that suits you (pay particular attention to the **"DB\_TYPE"**, **"SERVER\_NAME"** and **"SERVER\_DESCRIPTION"** attributes) or alternatively run the configurator.py tool interactively which will prompt you for important configuration options and rewrite the config.py file itself.
**IMPORTANT NOTE**: If you modify the **config.py** file directly and have selected **"DB\_TYPE"** as **"Text"** or left that field default (which is **"Text"**), you ***must*** run the configurator tool with no arguments: `$ ./configure_phxd.py` to generate the text database base files.

* Interactive configuration
The interactive tool provides an easy way to configure **phxd**'s most common configuration options. **phxd** should be configured before its first launch, by using the "configure_phxd.py" script as follow:
```
$ ./configure_phxd.py -i
```
The configurator script will prompt you with several configuration attributes in the following form `ATTRIBUTE_NAME=<default value> [Legal value/Legal value]`. If you wish to leave a specific attribute as default, press the "Enter" key. If you wish to change a particular attribute, enter the new value and press Enter, as shown in the following example:
```
$ ./configure_phxd.py -i
Choose a new value for each configuration attribute, and press enter or leave blank to leave the defaults in place.
If selecting 'DB_TYPE=Text' DB_USER, DB_PASS and DB_NAME don't apply.
DB_TYPE=Text [Text/MySQL]	MySQL
DB_USER=root	testuser
DB_PASS=	
DB_NAME=phxd	newservername
...
```
Once all the questions have been answered, the configurator program will exit, rewrite the **config.py** file according to the new attribute values given (or leaving all the options "as is" if none were changed), and generate the initial text database files (if a **"Text"** DB type was chosen).

* Editing **config.py** file directly
This is recommended for Users with some knowledge of Python, since the config.py file is actually a Python file that gets imported into the program. Attributes can be changed at will, and this method is the only way to register the server on trackers (see previous ["Configuration attributes"](#configuration-attributes) section). Once the attributes have been modified, make sure to run `$ ./configure_phxd.py`to generate the appropriate supporting files before running **phxd** for the first time.

# Installation
## Running phxd on a traditional operating system
There is no setup.py or other install package supplied with **phxd**. The program can be launched directly by simply invoking it in **Python 2.7**:
`$ python2 phxd`

Alternatively, a systemd service file could be created to run **phxd** on startup. Pay particular attention to the **"DB\_FILE\_\*"** attributes if you are using a **"DB\_TYPE"** of **"Text"** as **phxd** will create those database files by default to a **"textdb"** subdirectory relative to itself, which could be problematic if the program is moved to a system directory like **/usr/sbin**. The **"DB\_FILE\_BASEPATH"** property can be altered to specify an absolute path instead. The same warning is also true for the **"LOG\_FILE"** attribute, in which the **phxd** event logs will be stored by default.
## Running phxd as a Docker container
This is by far the easiest and most reliable method of installing **phxd**. A **Dockerfile** is supplied inside this repository to create a **~60MiB python:2-alpine** image that will run **phxd** as a container, using a docker Volume for **"Text"** database data and event logfiles. The container can be configured, built and deployed as follow:

1. Configure **config.py** as described in the earlier ["First time configuration"](#first-time-configuration) section.
2. If you are using a **"DB\_TYPE"** of **"Text"** or have set **"ENABLE\_FILE\_LOG"** to **True**, you must create a Docker volume where **phxd** data will be stored as follow:
```
# docker volume create <volumename>. We'll use "phxdvol" as a <volumename> in this example.
docker volume create phxdvol
```
**NOTE:** You can replace the Volume name as you see fit, or use an existing Volume if preferred.
3. Now it is time to build your **phxd** Docker image. the config.py file will be copied directly into the image:
```
# This must be ran from inside the "phxd" git repository directory
docker build -t phxd .
```
4. Once the Docker image has been built, the **phxd** container can be ran as follow:
```
docker run -v phxdvol:/app/textdb -d -p 5500:5500 -p 6667:5500 --restart=unless-stopped phxd:latest
```

* The **"-v"** option specifies which Volume should be mapped into the container and where should it be mounted.
* The **"-d"** option tells Docker to detach from this container (i.e. run it in the background as a daemon)
* The **"-p"** options tell Docker which ports to listen to on the host OS and where to remap them inside the container.
    - We remap port **5500** which is the default Hotline port to the container port 5500 which **phxd** listens to
    - We also remap port **6667** to the container as IRC clients will by default use that port and **phxd** only listens to a single, shared port.
* The **"--restart=unless-stopped"** option will tell Docker to restart this container automatically on reboot or after a crash.
* The last positional argument **"phxd:latest"** tells Docker to use the latest version of the "**phxd**" image we built earlier.

**Before** running the command, make sure all options match your configuration if you are altered the defaults:

* **DO** replace the **"phxdvol"** name with the Volume name you chose earlier.
* **DO** replace **"textdb"** from the **"/app/textdb"** argument with the **"DB\_FILE\_BASEPATH"** attribute from the **config.py** file if you have modified it.
* **DO** adjust the **"-p"** options to map the **"SERVER\_PORT"** configuration option if you have changed it (it defaults to **5500**).
* **DO** change the **"--restart=unless-stopped"** option if you do **not** want **phxd** to **restart automatically** on reboot.

Once you have executed the above `docker run` command, your container should be running and visible in Docker using `docker ps`:
```
$ docker ps
CONTAINER ID        IMAGE               COMMAND             CREATED             STATUS              PORTS                                            NAMES
78978978989         phxd:latest         "python phxd"       6 days ago          Up 5 days           0.0.0.0:5500->5500/tcp, 0.0.0.0:6667->5500/tcp   some_funny_name
```
### Reconfiguring config.py
Since the **config.py** file gets copied directly into the **phxd** Docker image when first built, it cannot be changed easily after the image is built.
A solution to this problem is to rebuild the Docker image if changes are made to the **config.py** file. If you have changed the file, run the following commands to stop, rebuild and restart the **phxd** container:
1. **Rebuild** the container (after having made changes to the **config.py** file):
```
# This must be ran from inside the "phxd" git repository directory
docker build -t phxd .
```
2. **Stop** the running **phxd** running container instance. This would have been necessary anyways as the config file is only read on **phxd**'s startup:
```
# Use docker stop <container_name>, so following our earlier example we would issue:
docker stop some_funny_name
```
3. **Restart** the **phxd** container with the latest image we have just built:
```
# NOTE: edit the following command according to your parameters
docker run -v phxdvol:/app/textdb -d -p 5500:5500 -p 6667:5500 --restart=unless-stopped phxd:latest
```
*Since we are using a Docker Volume to store all of **phxd**'s user data, the server should restart in the same state and with the same logs as the previous instance, which means that it is safe to destroy running containers instances and rebuild the Docker image with changes to the code or **config.py** and will not result in lost metadata or User data.*

# Usage
Once running, **phxd** can be connected to by pointing any Hotline or IRC client at its config.py "SERVER\_PORT".
* **Hotline**
When using a Hotline client, you can connect to the server as "Guest" by using a username of "guest" and no password. Guest access is fairly limited, and this is only useful to test your server. You **will** need to login as "admin" using a default password of "adminpass" and immediately change the admin password to a pass of your choice, or delete the admin account (after creating another priviledged account of course).
* **IRC**
When using an IRC client, after connecting to the server you will be greeted with the following message:

```
12:40 !phxd.server.tld *** Welcome to Hotline
12:40 !phxd.server.tld *** You are NOT logged in
12:40 !phxd.server.tld *** Please send '/msg loginserv login password' to proceed.
12:40 !phxd.server.tld *** If you do not have an account, use '/msg loginserv guest' to proceed.
```

You **must** login either as **"guest"** or as any other User (e.g. **"admin"**) in order to access any functionality of the server.
To login simply send a **private message** to **"loginserv"** with your **username** and **password**.
**NOTE:****phxd** doesn't support encryption or SASL, your user and password will be sent in cleartext. Make sure to use a unique password for **phxd** to avoid password reuse with other services.
To login as **guest**, issue the following command: `/msg loginserv guest`.
The server will **"force-join"** you to the **#public** channel. This channel actually corresponds to the **public chat** from the Hotline server. Any messages you type there will be visible to all other Hotline and IRC Users.
To issue a **private message**, simply call `/msg <targetnick> message contents`, like you would on a "normal" IRC server.

# Caveats
Not all standard IRC commands are supported, unsupported commands will be replied by **"421: Unknown command"** followed by **"NOTICE: HL Error"**.
Issuing any other commands than **"NICK"** or **"USER"** as **first command** upon connecting to the server will be replied with **"421: Unknown command"** and will trigger a connection closure by the server. An exception is made for **"CAP"** commands such as **"CAP LS"** which are ignored before a **"NICK"** or **"USER"** command is received.

So far, [**Limechat**](http://limechat.net/mac/) on Mac, [**irssi**](https://irssi.org/) and [**znc**](https://wiki.znc.in/ZNC) on Linux have been successfuly tested as client connecting to **phxd**'s current version.
