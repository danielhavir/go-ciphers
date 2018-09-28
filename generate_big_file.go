package main

import "io/ioutil"

func main() {
	// Initialize 100MB array with zeros
	zeros := make([]byte, 104857600)

	err := ioutil.WriteFile("bigfile.txt", zeros, 0664)

	if err != nil {
		panic(err)
	}
}
