import React from 'react';
import DOMPurify from 'dompurify';

export function Bio({ html }: { html: string }) {
  return (
    // codelens-expect: UNSAFE_HTML
    <div dangerouslySetInnerHTML={{ __html: html }} />
  );
}

export function SafeBio({ html }: { html: string }) {
  return <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />;
}

export async function load(db: any, id: string): Promise<unknown> {
  // codelens-expect: SQL_INJECTION
  return db.$queryRawUnsafe(`SELECT * FROM "User" WHERE id = '${id}'`);
}

export async function loadOk(db: any, id: string): Promise<unknown> {
  return db.user.findUnique({ where: { id } });
}
