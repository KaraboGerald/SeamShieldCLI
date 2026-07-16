"use client";
// Deliberately vulnerable fixture: server SDK in a client component.
import admin from "firebase-admin";

export const db = admin.firestore();
