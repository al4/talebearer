talebearer
==========
_noun_

A person who spreads scandal or tells secrets; gossip

What this app does
------------------

Talebearer takes an input properties file, reads any secret placeholder values from Vault, and writes the resulting properties map to an output properties file.

Secret placeholders are denoted by `{{ }}`, i.e. double curly braces). Talebearer queries vault for the path given within the braces. If a secret is found, it will replace the value with that from Vault, otherwise, it will replace the path with an error message.

The path within the braces is of the form `path/to/secret!key`, i.e. `vault write secret/example foo=bar` would be referenced by `secret/example!foo`.

Examples
--------

For the following properties file:
```
foo={{ secret/example!foo }}
key1=value1
```

And the following in vault:
```
vault write secret/example foo=bar
```

The output properties file should contain:
```
foo=bar
key1=value1
```

Usage
-----
Ensure the vault client environment variables are set, e.g:
```sh
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=d1bc686b-b987-3773-ad7d-15655cb833f4
```

```
talebearer -input-file ./examples/example.properties -output-file ./test.properties
```
