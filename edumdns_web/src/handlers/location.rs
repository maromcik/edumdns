// pub async fn get_locations(
//     request: HttpRequest,
//     identity: Option<Identity>,
//     session: Session,
//     state: web::Data<AppState>,
// ) -> Result<HttpResponse, WebError> {
//     let i = authorized!(identity, request.path());
//     let template_name = "location/index.html";
//     let env = state.jinja.acquire_env()?;
//     let template = env.get_template(&template_name)?;
//
//
// }
