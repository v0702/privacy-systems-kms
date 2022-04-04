package com.company.database;

import com.company.DomainKeys;

public class DatabaseEntry {
    int id;
    private DomainKeys domainKeys;

    public DatabaseEntry(int id, DomainKeys domainKeys) {
        this.id = id;
        this.domainKeys = domainKeys;
    }

    public int getId() {
        return this.id;
    }
    public DomainKeys getDomainKeys() {
        return this.domainKeys;
    }

    @Override
    public String toString() {
        return "-------------" +
                " id=" + id;
    }
}
