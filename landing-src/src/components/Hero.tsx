import Button from "./Button";
import HeroRecord from "./HeroRecord";
import Section from "./Section";

const chromeStoreUrl =
  "https://chromewebstore.google.com/detail/shieldai-transaction-fire/abpcgobnpgbkpncodobphpenfpjlpmpk";
const telegramUrl = "https://t.me/shieldbot_bnb_bot";

export default function Hero() {
  return (
    <Section id="hero" title="Know before you sign." level="h1">
      <div className="grid grid-cols-1 items-start gap-10 lg:grid-cols-[minmax(0,4fr)_minmax(0,8fr)] lg:gap-12">
        <div className="lg:pt-2">
          <p className="max-w-[34em] text-base leading-7 text-secondary md:text-lg">
            ShieldBot checks a transaction before your wallet signs it, and says
            Unknown when a check cannot run.
          </p>
          <div className="mt-6 flex flex-wrap gap-3">
            <Button href={chromeStoreUrl}>Add to Chrome</Button>
            <Button variant="secondary" href={telegramUrl}>
              Open in Telegram
            </Button>
          </div>
        </div>
        <div className="min-w-0">
          <HeroRecord />
        </div>
      </div>
    </Section>
  );
}
