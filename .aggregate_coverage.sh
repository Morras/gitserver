set -e
echo "" > coverage.txt

#Inspired by the answer to http://stackoverflow.com/questions/9612090/how-to-loop-through-file-names-returned-by-find
#And the initial script by https://github.com/codecov/example-go

# Make sure globstar is enabled
shopt -s globstar
for profile in **/*.coverprofile; do # Whitespace-safe and recursive
    cat $profile >> coverage.txt
    rm $profile
done
