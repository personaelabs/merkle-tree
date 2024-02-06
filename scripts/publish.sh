#!/bin/bash
new_version=$1

# Build the wasm package
wasm-pack build && 
cd pkg && 

# Rename the name field in package.json to @personaelabs/merkle-tree
jq '.name="@personaelabs/merkle-tree"' package.json > package.json.tmp && 
mv package.json.tmp package.json && 

# Set the new version
npm version $new_version && 

# Publish the package
npm publish --access public
