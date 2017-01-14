types = ['simple', 'complex', 'avcomp', 'avtest']
num_id = raw_input("please enter number of ids")
for i in range(1, int(num_id)):
    for item in types:
        print "python get_result.py -i " + str(i) + " -t " + item + " >> result.csv"
    print 'echo "' + str(i) + '" >> result.csv'
