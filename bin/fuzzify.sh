
# sanity check 
if [ $# -eq 0 ]
  then
    echo "No Binary name or path provided."
    echo "To use this, simply give the program the name of the binary"
    echo "like so: ./fuzzify ls"
    echo "It will try to reolve it by looking in your path."
    exit 1
fi

# get all the linked libs
libs=$(ldd $(which $1) | grep so | sed -e '/^[^\t]/ d' | sed -e 's/\t//' | sed -e 's/.*=..//' | sed -e 's/ (0.*)//' | grep -o '^\/.*') 

# create the location to store the fuzzable binary
mkdir $1

# make a libs storage and a way to undo the fuzzification
cd $1
mkdir libs
touch unfuzzify.sh

# loop all the libs and save their old location
for lib in $libs; do
	cp $lib libs/
	
	lib_name=$(echo $lib | sed 's/.*\///') 
	echo "cp libs/$lib_name $lib" >> unfuzzify.sh
done

# make it re runable
cp $(which $1) .
chmod +x unfuzzify.sh

# make a tar for the target 
cd ..
tar -czvf $1.tar.gz $1
rm -r $1


