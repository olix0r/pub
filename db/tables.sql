-- Tables
PRAGMA foreign_keys=ON;
BEGIN TRANSACTION;
CREATE TABLE Species (name TEXT PRIMARY KEY);
CREATE TABLE Entity(
    id TEXT PRIMARY KEY,
    species TEXT REFERENCES Species(name),
    primary_key_id TEXT REFERENCES Key(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE KeyType(name TEXT PRIMARY KEY);
CREATE TABLE Key(
    id TEXT PRIMARY KEY,
    type TEXT REFERENCES KeyType(name),
    data BINARY,
    comment TEXT,
    entity_id TEXT REFERENCES Entity(id) DEFERRABLE INITIALLY DEFERRED
);
CREATE TABLE Realm(range TEXT, domain TEXT, comment TEXT);
CREATE TABLE RealmKey(
    range TEXT,
    domain TEXT,
    key_id TEXT REFERENCES Key(id),
    PRIMARY KEY(range, domain, key_id),
    FOREIGN KEY(range, domain) REFERENCES Realm(range, domain)
);
COMMIT;
