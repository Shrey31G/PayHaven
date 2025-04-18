import { type JSX } from "react";

export function Card({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}): JSX.Element {
  return (
    <div className="bg-white rounded-lg shadow-md overflow-hidden border border-[#0a2351]">
      <div className="px-6 py-4 bg-gray-50 border-b border-[#0a2351] ">
        <h3 className="text-lg font-medium text-gray-900">{title}</h3>
      </div>
      <div className="px-6 py-4">
        {children}
      </div>
    </div>
  );
}