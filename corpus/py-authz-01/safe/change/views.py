from flask import abort, jsonify

from app import app, current_user_id
from models import load_invoice


@app.route("/invoices/<int:invoice_id>")
def show_invoice(invoice_id):
    invoice = load_invoice(invoice_id)
    if invoice is None:
        abort(404)
    if invoice.owner_id != current_user_id():
        abort(404)
    return jsonify(id=invoice.id, total_cents=invoice.total_cents)
