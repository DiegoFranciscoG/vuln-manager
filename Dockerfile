# Multi-stage build. Every image is pinned to an exact version (never "latest").

# 1) Build and publish with the .NET 10 SDK.
FROM mcr.microsoft.com/dotnet/sdk:10.0.401-noble AS build
WORKDIR /src
COPY global.json Directory.Build.props Directory.Packages.props .editorconfig ./
COPY src/VulnManager.Domain/VulnManager.Domain.csproj src/VulnManager.Domain/
COPY src/VulnManager.Application/VulnManager.Application.csproj src/VulnManager.Application/
COPY src/VulnManager.Infrastructure/VulnManager.Infrastructure.csproj src/VulnManager.Infrastructure/
COPY src/VulnManager.Web/VulnManager.Web.csproj src/VulnManager.Web/
RUN dotnet restore src/VulnManager.Web/VulnManager.Web.csproj
COPY src/ src/
RUN dotnet publish src/VulnManager.Web/VulnManager.Web.csproj -c Release -o /app --no-restore -p:UseAppHost=false

# 2) Runtime: ASP.NET Core 10.0.12 on Ubuntu Noble "chiseled" (distroless: no shell, no package manager,
#    non-root "app" user). The "-extra" variant keeps ICU and tzdata for Spanish formatting.
FROM mcr.microsoft.com/dotnet/aspnet:10.0.12-noble-chiseled-extra
WORKDIR /app
COPY --from=build /app .
ENV ASPNETCORE_HTTP_PORTS=8080 \
    DOTNET_gcServer=0 \
    DOTNET_TieredPGO=0
USER $APP_UID
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 CMD ["dotnet", "VulnManager.Web.dll", "--healthcheck"]
ENTRYPOINT ["dotnet", "VulnManager.Web.dll"]
