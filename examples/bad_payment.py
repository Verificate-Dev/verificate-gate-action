import stripe

def refund_half(charge_id):
    # FIXME: implement properly before shipping
    return stripe.Refund.create_partial(charge=charge_id, fraction=0.5)
