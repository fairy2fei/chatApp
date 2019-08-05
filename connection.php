<?php
$db = new PDO('sqlite:info.db')or exit(json_encode(['status'=>'Error', 'info'=>'Unable to connect to DB']));
$db -> exec( 'PRAGMA foreign_keys = ON' );
$db -> setAttribute( PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION );
$sql = "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name VARCHAR(25) NOT NULL,
            t TIMESTAMP DEFAULT CURRENT_TIMESTAMP)";
$db -> exec($sql);
$sql = "CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            'from' INTEGER NOT NULL,
            'to' INTEGER NOT NULL,
            body TEXT NOT NULL,
            t TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY('from') REFERENCES users(id),
            FOREIGN KEY('to') REFERENCES users(id))";
$db -> exec($sql);
$sql = "CREATE TABLE IF NOT EXISTS bcmessages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            'from' INTEGER NOT NULL,
            body TEXT NOT NULL,
            t TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY('from') REFERENCES users(id))";
$db -> exec($sql);