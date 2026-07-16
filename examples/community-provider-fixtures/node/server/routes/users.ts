import express from "express";
const router = express.Router();
router.delete("/users/:id", async (req, res) => res.json({ deleted: req.params.id }));
export default router;
