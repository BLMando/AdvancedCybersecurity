## Setup
Dal root folder lanciare:

```bash
docker build -f identity_pki/Dockerfile . -t identity-pki    
docker run --rm -p 8080:8080 -v "$PWD/certs/identity_pki:/data/certs" identity-pki   
```

# Enrollment (macOS & Windows)
Lo script rileva automaticamente l'hardware (Keychain su Mac, TPM su Windows).

```bash
# Enrollment standard (rileva MAC e CPU automaticamente)
python3 scripts/enroll.py --cn "paolo.roselli" --role "doctor" --department "Cardiologia"

# Enrollment con metadati manuali completi
python3 scripts/enroll.py --cn "paolo.roselli" --role "admin" --department "IT" --mac "DE:AD:BE:EF:00:11" --cpu "Apple M2 Max"
```

### Autenticazione (macOS & Windows)
```bash
python3 scripts/authenticate.py
```

## Struttura Progetto
- `scripts/enroll.py`: Registrazione identità hardware.
- `scripts/authenticate.py`: Verifica identità hardware.
- `scripts/macos/`: Helper nativo Swift per macOS.
- `scripts/windows/`: Helper PowerShell per Windows (TPM).

---

# Prossime modifiche:
- [ ] Se utente non riconosciuto mandarlo avanti come guest
- [ ] Aggiungere modelli statistici o addestramento per la parte degli attacchi
- [ ] Aggiungere modelli di machine learning per valutare il comportamento anomalo --> disponibili in rete