# Manual

This document describes how to use the propsed tooling that was submitted

## Network analysis tool

The list of command line arguements that one may provide is listed through

```
./ecnDetector -h
```

the two main command line arguements of interest are...

```
./ecnDetector -f [FILE]
```

Which defines the dataset to utilise, there are datasets contained as git lfs objects in the datasets directory

additionally we must also provide an output folder with the following argument

```
./ecnDetector -d [DIRECTORY]
```

to prevent permission errors its generally advisable to utilise some variant of the following commands

```
mkdir -p ouput_dir/keystore
chmod -r ugo+rwx output_dir
```

## Analysis tool

One can use the data analysis tool as follows

first changing into the correct directory and installing requirements

```
cd individualProject/src/analysis
pip install -r requirements.txt
```

Additionally we require that redis be installed to store AS number information
The install instructions are located here https://redis.io/topics/quickstart

once installed, before running the data analysis tool. One should start the redis server with.

```
redis-server
```

given a directory `foo` containing trace data with the following structure

```
    instance 
        |
        |
        ----- trace0
                | 
                |
                ---- HOST-PROTO-FLAGS.pcap
    instance2
        |
        |
        ----- trace0
                |
                |
                ---- HOST-PROTO-FLAGS.pcap
```

we can run the data analysis tooling with the following command

```
python main.py -i foo -w . -o .
```
This will produce a variety of json files containing a simplified view of the provided data allowing for faster subsequent analysis (as the initial parse of data takes a very long time)

subsequent runs of the data analysis tool can be performed with

```
python main.py --from-json . -w . -o . --run-analysis
```

The output is largely unstructured / not very clean, but was the means used to produce most of the visualizations present within the dissertation.