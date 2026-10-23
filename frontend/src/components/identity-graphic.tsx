import { Box } from "@mui/material";

/** Original landing-page graphic, with a restrained variation for authentication. */
export function IdentityGraphic({
  variant = "home",
}: {
  variant?: "home" | "auth";
}) {
  const auth = variant === "auth";
  return (
    <Box
      aria-hidden="true"
      sx={{
        position: "relative",
        width: "100%",
        maxWidth: auth ? 360 : 420,
        aspectRatio: "1",
        mx: "auto",
      }}
    >
      {[
        { size: 280, opacity: 0.1 },
        { size: 360, opacity: 0.06 },
        { size: 420, opacity: 0.03 },
      ].map(({ size, opacity }) => (
        <Box
          key={size}
          sx={{
            position: "absolute",
            left: "50%",
            top: "50%",
            width: `${(size / 420) * 100}%`,
            height: `${(size / 420) * 100}%`,
            transform: "translate(-50%,-50%)",
            borderRadius: "50%",
            border: `1px solid rgba(99,102,241,${opacity})`,
          }}
        />
      ))}
      <Box
        sx={{
          position: "absolute",
          left: "50%",
          top: "50%",
          width: `${(200 / 420) * 100}%`,
          height: `${(200 / 420) * 100}%`,
          transform: `translate(-50%,-50%) rotate(${auth ? 45 : 0}deg)`,
          borderRadius: "26%",
          background:
            "linear-gradient(135deg,rgba(99,102,241,.24),rgba(59,130,246,.06))",
          boxShadow:
            "inset 0 1px rgba(255,255,255,.88),0 28px 60px rgba(99,102,241,.18)",
          "&::before": {
            content: '""',
            position: "absolute",
            inset: "12%",
            borderRadius: "19.7368%",
            background: "rgba(255,255,255,.5)",
          },
        }}
      />
      <Box
        sx={{
          position: "absolute",
          inset: 0,
          transform: auth ? "rotate(20deg)" : undefined,
        }}
      >
        {[
          { x: 110, y: -110, size: 12, color: "#6366f1" },
          { x: -140, y: 90, size: 12, color: "#3b82f6" },
          { x: 60, y: 130, size: 8, color: "#8b5cf6" },
        ].map(({ x, y, size, color }) => (
          <Box
            key={color}
            sx={{
              position: "absolute",
              left: `${50 + (x / 420) * 100}%`,
              top: `${50 + (y / 420) * 100}%`,
              width: `${(size / 420) * 100}%`,
              height: `${(size / 420) * 100}%`,
              borderRadius: "50%",
              bgcolor: color,
              boxShadow: "0 0 0 6px rgba(99,102,241,.12)",
            }}
          />
        ))}
      </Box>
    </Box>
  );
}
