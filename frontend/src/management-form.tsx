import { useLocation, useNavigate } from "react-router-dom";
import { FieldsForm, appFields, providerFields, userFields } from "./forms";
import type { ViewEnvelope, FormView } from "./contracts";
import { Heading, Panel, names, type Actions } from "./shared";
import { t, useLocale } from "./i18n";

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
        ? [
            ...userFields,
            ...(data.mode === "create"
              ? [
                  {
                    name: "password",
                    label: t("初始密码"),
                    type: "password",
                    required: true,
                  },
                ]
              : []),
          ]
        : providerFields;
  const immutableFields = new Set(["username", "code"]);
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
          fields={fields.map((field) =>
            data.mode === "edit" && immutableFields.has(field.name)
              ? { ...field, disabled: true }
              : field,
          )}
          initial={data.form}
          submit={(values) =>
            mutate(path, values, () => navigate(`/dashboard/${kind}`))
          }
        />
      </Panel>
    </>
  );
}
