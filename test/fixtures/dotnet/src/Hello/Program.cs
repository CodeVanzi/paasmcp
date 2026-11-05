var app = WebApplication.CreateBuilder(args).Build();
app.MapGet("/", () => "ok dotnet");
app.Run();
