// AI-Security-Audit-Skills test fixture | Vijaya Kumar L (Rise With VJ) | github.com/risewithvj | MIT
const router = require('express').Router();
const Stripe = require('stripe');
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

// Buy extra training seats
router.post('/', async (req, res) => {
  const session = await stripe.checkout.sessions.create({
    mode: 'payment',
    line_items: [{ price_data: { currency: 'inr', unit_amount: req.body.amount, product_data: { name: 'Training seats' } }, quantity: 1 }],
    success_url: 'https://example.invalid/ok',
    cancel_url: 'https://example.invalid/cancel',
  });
  res.json({ url: session.url });
});

module.exports = router;
