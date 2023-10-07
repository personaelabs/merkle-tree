Save Merkle proofs in JSON

```
cargo run --release --bin save_proofs
```

- All csv files in `csv/` will be processed and the Merkle proofs will be saved in `out/`.
- A mapping between the Merkle roots and the set names will be saved in `out/root_to_label_mapping.json`.
