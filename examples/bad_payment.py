import stripe

def refund_half(charge_id):
    # FIXME: implement before shipping
    return stripe.Refund.create_partial(charge=charge_id, fraction=0.5)  # invented API
