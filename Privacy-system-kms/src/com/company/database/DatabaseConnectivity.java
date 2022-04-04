package com.company.database;
import java.sql.*;

public class DatabaseConnectivity {
    Connection c = null;
    Statement stmt = null;
    PreparedStatement pStmt = null;
    int currentID;//TODO: will not work as intended
    int counterCurrent;

    public DatabaseConnectivity() {
    }

    public void Insert(DatabaseEntry entry) {
        try {
            currentID = currentID+1;
            counterCurrent = counterCurrent+1;
            pStmt = c.prepareStatement(
                    "INSERT INTO KEYS (ID,DOMAINKEYS) " + "VALUES ("+currentID+", "+entry.getDomainKeys()+");"
            );
            //pStmt.setBytes(1,entry.getDomainKeys().);
            pStmt.executeUpdate();
            pStmt.close();
            c.commit();
            System.out.println("-. Records created successfully.");
        } catch ( Exception e ) {
            System.err.println("-* Error inserting: " + e.getMessage() );
        }
    }

    public DatabaseEntry[] Select() {
        try {
            stmt = c.createStatement();
            ResultSet rs = stmt.executeQuery( "SELECT * FROM PASSWORDS;" );
            DatabaseEntry[] entriesArray = new DatabaseEntry[counterCurrent];

            for (int i=0;i<entriesArray.length;i++) {
                rs.next();
                //entriesArray[i] = new DatabaseEntry(rs.getInt("id"),rs.getBytes("password"),rs.getString("username"),rs.getString("email"),rs.getString("website"));
            }
            rs.close();
            stmt.close();
            System.out.println("-. Operation done , showing "+entriesArray.length+" entrances.");
            return entriesArray;
        } catch ( Exception e ) {
            System.err.println("-* Error selecting table: " + e.getMessage() );
            return new DatabaseEntry[0];
        }
    }

    private void CreateTable() {
        try {
            stmt = c.createStatement();
            String sql = "CREATE TABLE KEYS " +
                    "(ID INT PRIMARY KEY NOT NULL," +
                    " DOMAINKEYS BLOB NOT NULL, ";
            stmt.executeUpdate(sql);
            stmt.close();
            System.out.println("-. Table created successfully.");
        }catch(Exception e) {
            System.err.println("-* Error creating table: " + e.getMessage());
        }
    }

    public void DatabaseConnect() {
        try {
            Class.forName("org.sqlite.JDBC");
            c = DriverManager.getConnection("jdbc:sqlite:test.db");
            c.setAutoCommit(false); //TODO: check on later

            DatabaseMetaData dbm = c.getMetaData();
            ResultSet tables = dbm.getTables(null, null, "PASSWORD", null);
            if (tables.next()) {
                CreateTable();
            }
            System.out.println("-. Opened database successfully.");
        }catch(Exception e) {
            System.err.println("-* Error connecting to db: " + e.getMessage());
        }

        try {//TODO: prob good idea to put this somewhere different
            stmt = c.createStatement();
            ResultSet rs = stmt.executeQuery("SELECT COUNT(ID) FROM PASSWORDS;");
            while(rs.next()) {
                currentID = rs.getInt(1);
                counterCurrent = rs.getInt(1);
                rs.close();
                stmt.close();
            }
        } catch ( Exception e ) {
            System.err.println("-* Error Counting tables: " + e.getMessage());
        }
    }
    public void CloseDatabaseConnect() {
        try {
            stmt.close();
            pStmt.close();
            c.close();
            System.out.println("-. Closed database successfully.");
        }catch(Exception e) {
            System.err.println("-* Error closing to db: " + e.getMessage());
        }
    }

}
