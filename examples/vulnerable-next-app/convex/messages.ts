// Deliberately vulnerable fixture: public mutation, no caller check.
import { mutation } from "./_generated/server";

export const send = mutation({
  handler: async (ctx, { body }) => {
    await ctx.db.insert("messages", { body });
  },
});
