export function initials(name: string): string {
  return name.split(" ").map((part) => part.charAt(0)).join("");
}
