import { providerPresets } from "./provider-presets";
import { can } from "./permissions";
import { useLocation, useNavigate } from "react-router-dom";
import { FieldsForm, appFields, providerFields, userFields } from "./forms";
import type { ViewEnvelope, FormView } from "./contracts";
import { Heading, Panel, names, type Actions } from "./shared";
import { t, useLocale } from "./i18n";
import { errorText } from "./api";

export function ManagementForm({
  page,
  mutate,
}: {
  page: ViewEnvelope<FormView>;
  mutate: Actions["mutate"];
}) {
  useLocale();
  const { view, data } = page;
  const navigate = useNavigate();
  const { pathname: path } = useLocation();
  const kind = view.startsWith("App")
    ? "apps"
    : view.startsWith("User")
      ? "users"
      : "providers";
  const fields =
    kind === "apps"
      ? appFields
      : kind === "users"
        ? data.mode === "create"
          ? [
              {
                name: "email",
                label: t("邀请邮箱"),
                type: "email",
                required: true,
              },
            ]
          : userFields.filter((f) =>
              ["email", "phone"].includes(f.name)
                ? can(data.layout, "users.contact.update")
                : f.name !== "username" && can(data.layout, "users.update"),
            )
        : providerFields;
  const immutableFields = new Set(["code"]);
  if (kind === "providers") {
    immutableFields.add("kind");
    for (const name of ["issuer", "client_id", "userinfo_endpoint"]) {
      if (
        data.form[name] &&
        (name !== "userinfo_endpoint" || data.form.kind !== "oidc")
      )
        immutableFields.add(name);
    }
  }
  return (
    <>
      <Heading
        title={t("{{0}}{{1}}", {
          "0": t(data.mode === "create" ? "新建" : "编辑"),
          "1": t(names[kind]),
        })}
        description={t("完善基础信息，保存后立即生效。")}
        back={`/dashboard/${kind}`}
      />
      <Panel title={t("基本信息")}>
        <FieldsForm
          key={path}
          presets={
            kind === "providers" && data.mode === "create"
              ? providerPresets
              : undefined
          }
          fields={fields.map((field) =>
            data.mode === "edit" && immutableFields.has(field.name)
              ? { ...field, disabled: true }
              : field,
          )}
          initial={data.form}
          serverError={data.error ? errorText(data.error) : ""}
          submit={(values) =>
            mutate(path, values, () => navigate(`/dashboard/${kind}`))
          }
        />
      </Panel>
    </>
  );
}
