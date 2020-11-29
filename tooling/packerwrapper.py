import os
import subprocess
import argparse
import json

'''
Tactiacal band aid script to assist with getting ami-ids from packer build
into terraform in a tfvars file, better ways to solve this issue exist
'''

def get_ami_from_data(arg):
    if len(arg) < 3:
        return None
    
    if arg[1] != "id":
        return None
    
    region, ami = arg[2].split(':')
    return (region, ami)


parser = argparse.ArgumentParser(description="Parse output from packer build")
parser.add_argument("--file", help="packer configuration file")
parser.add_argument("--dry", help="parse from pre baked output")

args = parser.parse_args()

file = args.file
dry = args.dry

if not file and not dry:
    print("No file name")
    raise SystemExit

print("### Defer to packer build ###")

out_str = None

if dry:
    f = open(dry)
    out_str = f.read()

if file:
    try:
        out_stream = subprocess.check_output(["packer", "build","-machine-readable", file])
    except subprocess.CalledProcessError as err:
        print("Packer build call returned a non zero exit code")
    out_str = out_stream.decode("utf-8")

lines = out_str.split('\n')

out_json = {}

for line in lines:
    
    frag = line.split(',')
    if len(frag) < 6:
        continue
    timestamp,target,cat,*data = frag
    print(data)
    if target != "amazon-ebs":
        continue
    if cat != "artifact":
        continue
    ret = get_ami_from_data(data)

    if not ret:
        continue

    region, ami = ret
    out_json["{r}_ami".format(r=region)] = ami

with open("images.auto.tfvars.json", 'w') as outfile:
    json.dump(out_json, outfile)
