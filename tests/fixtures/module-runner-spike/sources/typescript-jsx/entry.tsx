const React = {
  createElement(tag: string, _props: unknown, child: string) {
    return tag + ":" + child;
  },
};
export const view: string = <section>ok</section>;
print(view);
