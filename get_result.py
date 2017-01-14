from __future__ import print_function
import requests
import ijson
import pprint
import ConfigParser
import argparse


def download_file(url):
    local_filename = url.split('/')[-1]
    r = requests.get(url, stream=True)
    with open(local_filename, 'wb') as f:
        for chunk in r.iter_content(chunk_size=1024):
            if chunk:
                f.write(chunk)
    return local_filename

def load_json(filename):
    with open(filename, 'r') as fd:
        parser = ijson.parse(fd)
        ret = {'signatures': {}, 'antivirus': {}}
        for prefix, event, value in parser:
            if prefix == "signatures.item.name":
                signature = value
                ret['signatures'][signature] = {}
                ret['signatures'][signature]['markcount'] = markcount
                ret['signatures'][signature]['severity'] = severity
                ret['signatures'][signature]['description'] = description
            if prefix == "signatures.item.markcount":
                markcount = str(value)
            if prefix == "signatures.item.severity":
                severity = str(value)
            if prefix == "signatures.item.description":
                description = str(value)
            if prefix.startswith("virustotal.scans") and prefix.endswith('.result'):
                # print(value)
                # av_name=prefix.split('.')[2]
                if value is not None:
                    av_name=prefix.split('.')[2]
                    ret['antivirus'][av_name]=value
        return ret

def rating(items, setting):
    config = ConfigParser.ConfigParser()
    config.read(setting + ".ini")
    total_rate = 0.0
    for item in items['signatures']:
        item_rate = 0.0
        if item == "antivirus_virustotal":
            for av in items['antivirus']:
                try:
                    rate = config.get('antivirus',av.lower())
                except ConfigParser.NoOptionError:
                    rate = config.get('default','antivirus_virustotal')
                item_rate += int(rate)/56.0
        else:
            try:
               rate = config.get('default',item)
            except ConfigParser.NoOptionError:
               rate = config.get('default',"level_"+str(items['signatures'][item]['severity']))
            item_rate += int(rate)/1.0
        total_rate += item_rate
    print(total_rate, end=',')

def main():
    parser = argparse.ArgumentParser(description='Malware Rating System')
    parser.add_argument('-i','--taskid', type=int, help='task id in cuckoo',required=True)
    parser.add_argument('-t','--type',choices=['simple', 'avtest', 'avcomp', 'complex'],required=True)
    args = parser.parse_args()
    task_id = args.taskid
    url = "http://172.31.60.31:3000/analyses/" + str(task_id) + "/reports/report.json"
    filename = download_file(url)
    items = load_json(filename)
    pp = pprint.PrettyPrinter(indent=2)
    # pp.pprint(items)
    # for item in items['signatures']:
    #     print item + items['signatures'][item]['severity']
    rating(items, args.type)


if __name__ == '__main__':
    main()
