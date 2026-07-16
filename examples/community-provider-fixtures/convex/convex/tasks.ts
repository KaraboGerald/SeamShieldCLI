import { mutation } from "convex/values";

export const createTask = mutation({
  args: { title: v.string() },
  handler: async (ctx, args) => ctx.db.insert("tasks", args),
});
