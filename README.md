# Save Merkle proofs in JSON

```
cargo run --release --bin save_proofs [input_file] [output_file]
```

- The input file should be a csv file with one address per line.
- The output file will be stored in the `out/` folder.

### Example
```
cargo run --release --bin save_proofs ./sample.csv sampleproofs
```
