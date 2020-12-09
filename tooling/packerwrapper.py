import os
import subprocess
import argparse
import json

'''
Tactiacal band aid script to assist with getting ami-ids from packer build
into terraform in a tfvars file, better ways to solve this issue exist
'''

# 1607469587,amazon-ebs,artifact,0,string,AMIs were created:\neu-west-1: ami-0a17648f88941e10b\neu-west-2: ami-0b0eef2e72efead39\n
def get_ami_from_data(arg):
    if len(arg) < 3:
        return None
    
    if arg[0] != "0":
        return None

    if arg[1] != "string":
        return None

    outDict = {}    
    regionAmiDesc = arg[2].split('\\n')
    amiNames = regionAmiDesc[0:]
    for elt in amiNames:
        nameami = elt.split(':')

        if len(nameami) != 2:
            continue
        

        name, ami = nameami
        if not ami:
            continue
        outDict[name.strip()] = ami.strip()
   
    return outDict 



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
    if target != "amazon-ebs":
        continue
    if cat != "artifact":
        continue

    print(data)
    ret = get_ami_from_data(data)

    if not ret:
        continue

    out_json = ret

with open("images.auto.tfvars.json", 'w') as outfile:
    json.dump(out_json, outfile)
