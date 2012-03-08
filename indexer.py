"""
Example of Annotation Indexer & Searcher

Author: jashing


Prerequest: 
* swift's client: so that command "swift" can be invoked by shell 

Usages: 
* cmd for annotating an object by cloudfuse:

  setfattr -n Annotation -v "hot dog" 1.jpg
  
* cmd for reading annotation from an object by cloudfuse:
  
  getfattr -n Annotation 1.jpg


Note: Please use "Annotation" as Metadata key so that this indexer.py can work.


"""

import os
import sys
import subprocess

# please modify host info
swift_cmd = 'swift -A https://127.0.0.1/auth/v1.0/ -U system:root -K testpass '

def main(path):
    # query swift pic container
    # build index file
    # keyin query & response 

    fann = { }
    # 1. list container's files
    ls_cmd = swift_cmd + " list " + path
    f = os.popen(ls_cmd)
    for file in f.readlines():
        #print file
        fann[file.strip()] = ""
    
    # 2. build index
    for fn in fann.keys():
        #print fn
        stat_cmd = swift_cmd + " stat " + path + " " + fn
        f = os.popen(stat_cmd)
        for line in f.readlines():
            #print line

            tokens = line.split(":")
            if tokens[0].strip() == "Meta Annotation":
                fann[fn] = tokens[1].strip()


    print "Indexing:"
    print fann

    print "\n\n"
    print "Ready to Search Now!!\n"
    while (True):
        keyword = raw_input("Enter you keywords:")
        if keyword == "quit":
            print "bye."
            exit(0)
            
        match_flag = 0
        for key in fann.keys():
            ann = fann[key]
            if ann.find(keyword) >= 0:
                print "file " + key + " match. [" + ann + "]\n"
                match_flag = 1
        if match_flag == 0:
            print "Not found."

if __name__ == '__main__':
    try:
        path = sys.argv[1]
    except IndexError:
        print 'use: %s container' % sys.argv[0]
    else:
        main(path)

