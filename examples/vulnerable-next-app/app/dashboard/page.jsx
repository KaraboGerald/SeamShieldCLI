"use client";
// Deliberately vulnerable fixture: the only guard runs in the browser.
export default function Dashboard({ user }) {
  if (!user) return null;
  return <div>Welcome back</div>;
}
