defmodule FixtureHex.MixProject do
  use Mix.Project

  def project do
    [
      app: :fixture_hex,
      version: "0.1.0"
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.4"}
    ]
  end
end
