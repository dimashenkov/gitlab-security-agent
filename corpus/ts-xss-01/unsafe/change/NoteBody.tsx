import React from "react";

type Note = { id: string; body: string };

// Renders a note authored by another user.
export function NoteBody({ note }: { note: Note }) {
  return (
    <article
      className="note"
      data-note-id={note.id}
      dangerouslySetInnerHTML={{ __html: note.body }}
    />
  );
}
