import bincopy
from sys import argv, exit
from os.path import exists



if __name__ == '__main__':

    assert len(argv) == 2, '%s requires a shex input file' % argv[0]
    assert exists(argv[1]), '%s file does not exist' % argv[1]


    binengine = bincopy.BinFile()
    binengine.add_file(argv[1])

    try:
        with open('%s.raw'%argv[1],'wb+') as fout:
            ln = fout.write(binengine.as_binary())
    except Exception as e:
        print('[!]Error converting file\n  Reason:\n   %s'%e.__str__())
        exit(1)

    print('[+] input file has been successfully converted'
          'in file %s.raw'%argv[1])
