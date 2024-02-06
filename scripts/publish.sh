#!/bin/bash
new_version=$1

# Build the wasm package
wasm-pack build --scope personaelabs --target nodejs && 
cd pkg && 

# Set the new version
npm version $new_version && 

# Publish the package
npm publish --access public
