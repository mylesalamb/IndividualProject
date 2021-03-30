Individual Project Tooling
--------------------------

This readme describes the contents of the software that was developed for the individual project to realise "Where is ECN stripped on the network". The tooling is broken into three distinct parts. Each contained within a specific folder

* "tool", a set of C files / bash scripts allowing for measurements to be taken from the network.

* "deploy", Terraform / deployment configuration, a set of installer scripts and terraform configuration targetting an AWS deployment.

* "analysis", a collection of python files for parsing outputted data from the network analysis tool and extracting key features of the data.

