from dataclasses import dataclass


@dataclass
class Invoice:
    id: int
    owner_id: int
    total_cents: int


def load_invoice(invoice_id: int) -> Invoice:
    """Fetch by primary key. Performs no access control of its own."""
    row = db.fetchone("SELECT id, owner_id, total_cents FROM invoices WHERE id = %s",
                      (invoice_id,))
    return Invoice(*row) if row else None
