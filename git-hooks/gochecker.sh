#!/bin/sh
formatfails=$(gofmt -l .)
if [ -n "$formatfails" ]; then
	echo "The following files are not correctly formatted:"
	echo "$formatfails"
	echo -e "\nYou can use e.g. 'gofmt -w .' to fix this. Abort."
	exit 1
fi

testfails=$(go test -short -race -covermode atomic -coverprofile profile.cov ./...)
if [ $? -ne 0 ]; then
	echo "$testfails"
	echo -e "\nUnit Tests have failed. Abort."
	rm -f profile.cov
	exit 1
fi

threshold=75

coveroutput=$(go tool cover -func profile.cov)
coverage=$(echo "${coveroutput}" | grep -E '^total:' | grep -oE '[0-9]{2}')
if [ $((coverage)) -lt $threshold ]; then
	echo "${coveroutput}"
	echo "Test coverage of ${coverage}% is under the threshold of $threshold%. Abort."
	rm -f profile.cov
	exit 1
fi

rm -f profile.cov
