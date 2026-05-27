# See https://aka.ms/customizecontainer to learn how to customize your debug container and how Visual Studio uses this Dockerfile to build your images for faster debugging.

# This stage is used when running from VS in fast mode (Default for Debug configuration)
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS base
RUN apt-get update && apt-get install -y --no-install-recommends \
    gss-ntlmssp \
    libldap-2.5-0 \
    iputils-ping \
    netcat-openbsd \
    dnsutils \
    nano \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /etc/ldap /etc/openldap \
    && echo "TLS_REQCERT never" >> /etc/ldap/ldap.conf \
    && echo "TLS_REQCERT never" >> /etc/openldap/ldap.conf

USER $APP_UID
WORKDIR /app

USER app

# This stage is used to build the service project
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
ARG BUILD_CONFIGURATION=Release
WORKDIR /src
COPY ["TestClient/TestClient.csproj", "TestClient/"]
RUN dotnet restore "./TestClient/TestClient.csproj"
COPY . .
WORKDIR "/src/TestClient"
RUN dotnet build "./TestClient.csproj" -c $BUILD_CONFIGURATION -o /app/build

# This stage is used to publish the service project to be copied to the final stage
FROM build AS publish
ARG BUILD_CONFIGURATION=Release
RUN dotnet publish "./TestClient.csproj" -c $BUILD_CONFIGURATION -o /app/publish /p:UseAppHost=false

# This stage is used in production or when running from VS in regular mode (Default when not using the Debug configuration)
FROM base AS final
WORKDIR /app
COPY --from=publish /app/publish .
ENTRYPOINT ["dotnet", "TestClient.dll"]