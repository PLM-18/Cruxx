const express = require('express');
const userRoutes = require('./userRoutes');
const productRoutes = require('./productRoutes');
const analyticsRoutes = require('./analyticsRoutes');

const router = express.Router();

router.use('/users', userRoutes);
router.use('/files', productRoutes);
router.use('/analytics', analyticsRoutes);

module.exports = router;