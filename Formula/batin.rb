class Batin < Formula
  desc "Security-hardened file type detection using magic bytes, entropy, and threat analysis"
  homepage "https://github.com/ahmeddwalid/batin"
  version "0.1.0"
  license "GPL-3.0-only"

  if OS.mac?
    if Hardware::CPU.intel?
      url "https://github.com/ahmeddwalid/batin/releases/download/v#{version}/batin-macos-x86_64"
      sha256 "PLACEHOLDER_SHA256_MACOS_INTEL"
    elsif Hardware::CPU.arm?
      url "https://github.com/ahmeddwalid/batin/releases/download/v#{version}/batin-macos-aarch64"
      sha256 "PLACEHOLDER_SHA256_MACOS_ARM"
    end
  elsif OS.linux?
    if Hardware::CPU.intel?
      url "https://github.com/ahmeddwalid/batin/releases/download/v#{version}/batin-linux-x86_64"
      sha256 "PLACEHOLDER_SHA256_LINUX_INTEL"
    elsif Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      url "https://github.com/ahmeddwalid/batin/releases/download/v#{version}/batin-linux-aarch64"
      sha256 "PLACEHOLDER_SHA256_LINUX_ARM64"
    end
  end

  def install
    if OS.mac? && Hardware::CPU.intel?
      bin.install "batin-macos-x86_64" => "batin"
    elsif OS.mac? && Hardware::CPU.arm?
      bin.install "batin-macos-aarch64" => "batin"
    elsif OS.linux? && Hardware::CPU.intel?
      bin.install "batin-linux-x86_64" => "batin"
    elsif OS.linux? && Hardware::CPU.arm? && Hardware::CPU.is_64_bit?
      bin.install "batin-linux-aarch64" => "batin"
    end
  end

  test do
    system "#{bin}/batin", "--version"
  end
end
