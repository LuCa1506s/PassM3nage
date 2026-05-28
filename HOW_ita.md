# HOW PassM3nage

## Overview

PassM3nage è un password manager offline e portatile scritto in Rust. È progettato per essere eseguito in un terminale locale, senza cloud, senza rete, senza estensioni browser e senza telemetria. Il progetto gestisce un vault cifrato con credenziali e offre backup/restauro sicuri dei file cifrati.

## Cosa fa

PassM3nage supporta le seguenti funzioni:

- Creare una password iniziale protetta al primo avvio.
- Aggiungere voci di servizio con username e password.
- Cercare servizi salvati tramite filtro in tempo reale.
- Visualizzare la password di una voce selezionata.
- Modificare username e password dopo la verifica della password iniziale.
- Cancellare una voce selezionata con conferma.
- Creare un backup cifrato locale del vault.
- Ripristinare un backup cifrato in `vault.json`.
- Gestire il rinnovo automatico del formato della vault legacy se necessario.
- Segnalare lo stato `OK` / `ERROR` in una barra di stato.

## Come funziona il progetto

### Avvio e login

- Alla prima esecuzione, viene chiesto di creare una password iniziale.
- La password deve contenere almeno 8 caratteri, un numero e un simbolo speciale.
- Viene generato un file `tech.json` contenente un salt casuale e un payload di controllo cifrato.
- `tech.json` serve a verificare la password all'accesso successivo.
- Se `vault.json` esiste ma `tech.json` è assente, il programma avvia una schermata di rischio sicurezza (`secury recovery risk`) e impedisce l'accesso finché l'utente non esce o distrugge il vault.

### File principali creati

- `tech.json`: contiene il salt casuale e un piccolo valore di controllo cifrato per verificare la password iniziale.
- `vault.json`: contiene le voci del vault cifrate e il flag di registro.

### Struttura dell'applicazione

- `src/main.rs`: logica principale dell'app, flussi di backup, login, salvataggio e caricamento.
- `src/crypto/kdf.rs`: derivazione della chiave dall'password usando Argon2id.
- `src/crypto/cipher.rs`: crittografia autenticata con XChaCha20-Poly1305.
- `src/vault/format.rs`: formato binario del vault e intestazione autenticata.
- `src/vault/entry.rs`: struttura delle voci del vault e gestione della serializzazione.
- `src/vault/storage.rs`: salvataggio atomico del vault su disco.
- `src/tui/*`: interfaccia utente terminale.

## Funzionalità principali

### Aggiungere una voce

- `A` apre la schermata di inserimento.
- `Tab` passa tra campo servizio, username e password.
- `Enter` conferma il campo corrente.
- Se il servizio già esiste, il programma offre di sovrascrivere o creare una copia numerata.
- Le voci vengono salvate cifrate in `vault.json`.

### Ricerca e visualizzazione

- `S` apre il campo di ricerca.
- La ricerca filtra i servizi presenti nel vault.
- `W` e `S` spostano la selezione nei risultati.
- `Enter` mostra la password selezionata.
- `E` avvia la modifica dopo la richiesta della password iniziale.
- `C` elimina la voce selezionata.

### Backup cifrato

- `B` avvia la procedura di backup.
- L'utente fornisce una directory di destinazione.
- Viene copiato `vault.json` come `vault.backup.json` in quella directory.
- Se esiste `tech.json`, viene copiato anche come `tech.backup.json`.
- Il backup rimane cifrato e non viene decrittato durante l'operazione.

### Ripristino backup

- `U` avvia la procedura di upload/restore.
- L'utente fornisce il percorso completo di un backup cifrato.
- Il file selezionato viene copiato su `vault.json`.
- Se nello stesso percorso esiste `tech.backup.json`, viene copiato anche su `tech.json`.
- Il programma ricarica il vault e prova a decrittarlo con la password corrente.
- Se la password corrente non corrisponde al backup, lo stato riporta un errore.

## Come funziona la crittografia

### Derivazione della chiave (KDF)

PassM3nage utilizza Argon2id per derivare una chiave a 32 byte dalla password dell'utente.

Parametri usati:

- `memory_kb`: 65536 (64 MiB)
- `time_cost`: 3
- `parallelism`: 4
- `salt`: 16 byte casuali generati in `tech.json`

Il risultato è una chiave segreta a 32 byte utilizzata per tutte le cifrature del vault.

### Cifratura autenticata

Il progetto usa XChaCha20-Poly1305 con i seguenti elementi:

- `key`: 32 byte derivati da Argon2id
- `nonce`: 24 byte casuali generati per ogni operazione di cifratura
- `AAD`: dati aggiuntivi autenticati ma non cifrati

### Perché lo stesso password genera ciphertext diversi

È normale che con la stessa password si ottengano ciphertext diversi. Questo avviene perché:

- il salt in `tech.json` è casuale alla creazione del vault;
- ogni cifratura usa un nonce casuale diverso;
- il risultato è un ciphertext unico anche per lo stesso plaintext.

Questo comportamento è corretto e migliora la sicurezza.

### Verifica password

- `tech.json` contiene:
  - `salt`: il sale usato per la derivazione chiave
  - `check_ciphertext`: il valore cifrato
  - `check_nonce`: il nonce usato
- Il contenuto decifrato deve essere esattamente il segreto di controllo interno.
- Se la decrittazione fallisce, la password è errata o `tech.json` è stato manomesso.

## Sistema di backup

### Backup

- Viene copiato `vault.json` in `vault.backup.json` nella cartella scelta.
- Se `tech.json` è presente, viene copiato anche `tech.backup.json` nella stessa cartella.
- Il backup è composto da file cifrati, pertanto non espone username/password in chiaro.

### Ripristino

- L'utente fornisce il percorso di `vault.backup.json`.
- Se nello stesso percorso esiste `tech.backup.json`, viene ripristinato anche quello.
- Dopo la copia, il programma ricarica il vault e verifica che la password corrente possa decrittare i dati.
- Il ripristino fallisce in modo sicuro se la password non corrisponde.

## Uso rapido

Build:

```powershell
cargo build --release
```

Esecuzione:

```powershell
cargo run
```

Sul file compilato:

```powershell
.\target\release\passm3nage.exe
```

## Note di sicurezza

- PassM3nage protegge i dati da accessi offline non autorizzati.
- Non protegge da malware, keylogger, screen scraping o sistema operativo compromesso.
- Le chiavi e le password viene derivate e gestite con tipi sicuri.
- Sono utilizzate primitive crittografiche standard e non personalizzate.

## Struttura dei file

- `src/crypto/kdf.rs`: derivazione chiave Argon2id.
- `src/crypto/cipher.rs`: cifratura autenticata XChaCha20-Poly1305.
- `src/vault/format.rs`: serializzazione formato vault.
- `src/vault/storage.rs`: scrittura atomica su disco.
- `src/main.rs`: flusso principale, backup, restore, login e TUI.
- `src/tui/`: schermate e controllo utente.
- `src/clipboard/`: copia sicura negli appunti.

## Limitazioni

- L'implementazione è un prototipo e non deve ancora essere usata per password critiche in produzione.
- Il vault resta decrittato in memoria durante la sessione.
- Non c'è sincronizzazione cloud o condivisione remota.
- La sicurezza dipende dalla qualità della password iniziale e dall'integrità del dispositivo.