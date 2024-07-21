"user server";

import { lucia, validateRequest } from "@/auth";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";

export async function logout() {
  // 先检查是否登陆
  const { session } = await validateRequest();
  if (!session) {
    throw new Error("Unauthenticated");
  }

  // 让session失效
  await lucia.invalidateSession(session.id);

  // 创建一个空的cookie，
  const sessionCookie = lucia.createBlankSessionCookie();

  cookies().set(
    sessionCookie.name,
    sessionCookie.value,
    sessionCookie.attributes,
  );

  return redirect("/login");
}
